use std::collections::HashSet;
use std::ffi::c_void;
use std::io::{Read, Write};
use std::mem::size_of;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde::Serialize;
use serde_json::{Value, json};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED, GENERIC_READ, GENERIC_WRITE, GetLastError,
    HANDLE, INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    CopySid, GetLengthSid, GetTokenInformation, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
    TOKEN_QUERY, TOKEN_USER, TokenPrimary, TokenType, TokenUser,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX, ReadFile,
    SECURITY_EFFECTIVE_ONLY, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT, WriteFile,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    GetNamedPipeServerProcessId, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
    PIPE_UNLIMITED_INSTANCES, PIPE_WAIT, PeekNamedPipe, WaitNamedPipeW,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{GetForegroundWindow, GetWindowThreadProcessId};

use super::{
    PendingRequest, PendingRequests, RESIDENT_IPC_DEFAULT_TIMEOUT_MS, ResidentIpcFrame,
    ResidentIpcRequestHandler, client_hello, negotiate_client_hello, validate_request,
    validate_server_hello, write_frame,
};
use crate::command_loop::{
    MAX_NATIVE_REQUEST_BYTES, MAX_NATIVE_RESPONSE_BYTES, NativeMessage,
    configure_stdio_for_native_messaging, read_native_message_or_eof_with_limit,
};

const PIPE_PREFIX: &str = r"\\.\pipe\VaultKern.Resident.";
const PIPE_BUFFER_BYTES: u32 = 64 * 1024;
const PIPE_CONNECT_WAIT_MS: u32 = 5_000;
const REQUEST_POLL_INTERVAL: Duration = Duration::from_millis(25);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

pub struct WindowsResidentIpcServer {
    shutdown: Arc<AtomicBool>,
    pipe_name: Vec<u16>,
    listener: Option<JoinHandle<()>>,
}

pub fn start_windows_resident_ipc_server(
    handler: ResidentIpcRequestHandler,
) -> Result<WindowsResidentIpcServer> {
    let identity = ProcessIdentity::current().context("resolve resident IPC server identity")?;
    let pipe_name = wide_nul(&format!("{PIPE_PREFIX}{}", identity.sid_string));
    let first_pipe = create_server_pipe(&pipe_name, &identity.sid_string, true)
        .context("create the first resident IPC pipe instance")?;
    let shutdown = Arc::new(AtomicBool::new(false));
    let listener_shutdown = shutdown.clone();
    let listener_pipe_name = pipe_name.clone();
    let listener_sid = identity.sid;
    let listener = std::thread::Builder::new()
        .name("vaultkern-resident-ipc-listener".into())
        .spawn(move || {
            run_server_listener(
                first_pipe,
                listener_pipe_name,
                identity.sid_string,
                listener_sid,
                listener_shutdown,
                handler,
            );
        })
        .context("start resident IPC listener")?;

    Ok(WindowsResidentIpcServer {
        shutdown,
        pipe_name,
        listener: Some(listener),
    })
}

impl Drop for WindowsResidentIpcServer {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        let _ = open_client_pipe(&self.pipe_name);
        if let Some(listener) = self.listener.take() {
            let _ = listener.join();
        }
    }
}

pub fn run_windows_native_messaging_shim(
    browser_origin: &str,
    parent_window: Option<usize>,
) -> Result<()> {
    configure_stdio_for_native_messaging()?;
    let identity = ProcessIdentity::current().context("resolve native shim identity")?;
    let pipe_name = wide_nul(&format!("{PIPE_PREFIX}{}", identity.sid_string));
    let pipe = match open_client_pipe(&pipe_name) {
        Ok(pipe) => pipe,
        Err(error) => {
            let message = "VaultKern resident app is unavailable; start the Windows app and retry";
            let _ = write_startup_failure("resident_unavailable", message);
            return Err(error).context(message);
        }
    };
    if let Err(error) = verify_pipe_server(&pipe, &identity.sid) {
        let message = "VaultKern could not authenticate the resident app";
        let _ = write_startup_failure("resident_authentication_failed", message);
        return Err(error).context("authenticate resident IPC server");
    }
    if let Err(error) = perform_client_handshake(&pipe, browser_origin, parent_window) {
        let message = "VaultKern could not negotiate with the resident app";
        let _ = write_startup_failure("resident_connection_failed", message);
        return Err(error);
    }

    let (browser_events, receiver) = mpsc::channel();
    std::thread::Builder::new()
        .name("vaultkern-native-message-reader".into())
        .spawn(move || read_browser_messages(browser_events))
        .context("start native messaging input reader")?;

    forward_browser_messages(pipe, receiver)
}

fn write_startup_failure(code: &str, message: &str) -> Result<()> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    write_startup_failure_to(&mut stdin.lock(), &mut stdout.lock(), code, message)
}

fn write_startup_failure_to(
    reader: &mut impl Read,
    writer: &mut impl Write,
    code: &str,
    message: &str,
) -> Result<()> {
    let request_id =
        match read_native_message_or_eof_with_limit::<Value>(reader, MAX_NATIVE_REQUEST_BYTES)? {
            NativeMessage::Message(message) => request_id_from_value(&message),
            NativeMessage::DecodeError { request_id, .. } => request_id,
            NativeMessage::Oversized { .. } => None,
            NativeMessage::Eof => return Ok(()),
        };
    write_native_value(
        writer,
        &runtime_error_value(code, message),
        request_id.as_deref(),
    )
}

fn run_server_listener(
    mut pipe: Pipe,
    pipe_name: Vec<u16>,
    sid_string: String,
    expected_sid: Vec<u8>,
    shutdown: Arc<AtomicBool>,
    handler: ResidentIpcRequestHandler,
) {
    loop {
        if let Err(error) = connect_server_pipe(&pipe) {
            if !shutdown.load(Ordering::Acquire) {
                eprintln!("resident IPC accept failed: {error:#}");
            }
            return;
        }
        if shutdown.load(Ordering::Acquire) {
            return;
        }

        match create_server_pipe(&pipe_name, &sid_string, false) {
            Ok(next_pipe) => {
                let connection = pipe;
                let connection_sid = expected_sid.clone();
                let connection_handler = handler.clone();
                let _ = std::thread::Builder::new()
                    .name("vaultkern-resident-ipc-client".into())
                    .spawn(move || {
                        if let Err(error) =
                            serve_connection(connection, &connection_sid, connection_handler)
                        {
                            eprintln!("resident IPC client closed: {error:#}");
                        }
                    });
                pipe = next_pipe;
            }
            Err(error) => {
                eprintln!("resident IPC listener could not create another pipe: {error:#}");
                return;
            }
        }
    }
}

fn serve_connection(
    pipe: Pipe,
    expected_sid: &[u8],
    handler: ResidentIpcRequestHandler,
) -> Result<()> {
    verify_pipe_client(&pipe, expected_sid).context("authenticate resident IPC client")?;
    let pipe = Arc::new(pipe);
    let mut reader = PipeFrameReader::new(pipe.clone());
    let writer = Arc::new(Mutex::new(PipeWriter(pipe)));

    let hello = match read_pipe_frame_with_timeout(&mut reader, HANDSHAKE_TIMEOUT)
        .context("wait for resident IPC client hello")?
    {
        ResidentIpcFrame::ClientHello(hello) => hello,
        _ => anyhow::bail!("resident IPC client did not begin with a hello frame"),
    };
    let requested_parent_window = hello
        .parent_window
        .and_then(|value| usize::try_from(value).ok())
        .filter(|value| *value != 0);
    let hello = match negotiate_client_hello(hello) {
        Ok(hello) => hello,
        Err(error) => {
            let _ = send_frame(
                &writer,
                &ResidentIpcFrame::Error {
                    request_id: None,
                    code: "handshake_rejected".into(),
                    message: error.to_string(),
                },
            );
            return Err(error.context("reject resident IPC handshake"));
        }
    };
    send_frame(&writer, &ResidentIpcFrame::ServerHello(hello))?;

    let pending = PendingRequests::default();
    loop {
        let frame = match reader.try_read_frame() {
            Ok(frame) => frame,
            Err(error) => {
                pending.cancel_all();
                return Err(error.context("poll resident IPC client"));
            }
        };
        let Some(frame) = frame else {
            std::thread::sleep(REQUEST_POLL_INTERVAL);
            continue;
        };
        match frame {
            ResidentIpcFrame::Request {
                request_id,
                timeout_ms,
                message,
            } => {
                if let Err(error) = validate_request(&request_id, timeout_ms) {
                    send_frame(
                        &writer,
                        &ResidentIpcFrame::Error {
                            request_id: Some(request_id),
                            code: "invalid_request".into(),
                            message: error.to_string(),
                        },
                    )?;
                    continue;
                }
                let request = match pending.register(&request_id) {
                    Ok(request) => request,
                    Err(error) => {
                        send_frame(
                            &writer,
                            &ResidentIpcFrame::Error {
                                request_id: Some(request_id),
                                code: "duplicate_request".into(),
                                message: error.to_string(),
                            },
                        )?;
                        continue;
                    }
                };
                let parent_window =
                    resolve_request_parent_window(requested_parent_window, expected_sid);
                dispatch_request(
                    request,
                    timeout_ms,
                    message,
                    parent_window,
                    writer.clone(),
                    handler.clone(),
                );
            }
            ResidentIpcFrame::Cancel { request_id } => {
                if pending.cancel(&request_id) {
                    send_frame(
                        &writer,
                        &ResidentIpcFrame::Error {
                            request_id: Some(request_id),
                            code: "request_cancelled".into(),
                            message: "the resident IPC request was cancelled".into(),
                        },
                    )?;
                }
            }
            _ => {
                pending.cancel_all();
                anyhow::bail!("unexpected resident IPC frame after handshake");
            }
        }
    }
}

fn dispatch_request(
    request: PendingRequest,
    timeout_ms: u64,
    message: Value,
    parent_window: Option<usize>,
    writer: Arc<Mutex<PipeWriter>>,
    handler: ResidentIpcRequestHandler,
) {
    let request_id = request.request_id.clone();
    let cancellation = request.cancellation_token();
    let (result_sender, result_receiver) = mpsc::channel();
    let spawn_result = std::thread::Builder::new()
        .name("vaultkern-resident-ipc-request".into())
        .spawn(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                handler(message, cancellation, parent_window)
            }))
            .map_err(|_| "resident IPC request handler panicked".to_owned());
            let _ = result_sender.send(result);
        });
    if spawn_result.is_err() {
        if request.claim_response() {
            let _ = send_frame(
                &writer,
                &ResidentIpcFrame::Error {
                    request_id: Some(request_id),
                    code: "runtime_unavailable".into(),
                    message: "failed to start resident IPC request".into(),
                },
            );
        }
        return;
    }

    let response_request = request.clone();
    let response_request_id = request_id.clone();
    let response_writer = writer.clone();
    let response_spawn = std::thread::Builder::new()
        .name("vaultkern-resident-ipc-response".into())
        .spawn(move || {
            let deadline = Instant::now() + Duration::from_millis(timeout_ms);
            loop {
                if response_request.cancelled() {
                    return;
                }
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    if response_request.claim_response() {
                        response_request
                            .cancellation_token()
                            .store(true, Ordering::Release);
                        let _ = send_frame(
                            &response_writer,
                            &ResidentIpcFrame::Error {
                                request_id: Some(response_request_id),
                                code: "request_timeout".into(),
                                message: "the resident IPC request timed out".into(),
                            },
                        );
                    }
                    return;
                }
                match result_receiver.recv_timeout(remaining.min(REQUEST_POLL_INTERVAL)) {
                    Ok(Ok(message)) => {
                        if response_request.claim_response() {
                            let _ = send_runtime_response(
                                &response_writer,
                                response_request_id,
                                message,
                            );
                        }
                        return;
                    }
                    Ok(Err(message)) => {
                        if response_request.claim_response() {
                            let _ = send_frame(
                                &response_writer,
                                &ResidentIpcFrame::Error {
                                    request_id: Some(response_request_id),
                                    code: "runtime_panic".into(),
                                    message,
                                },
                            );
                        }
                        return;
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        if response_request.claim_response() {
                            let _ = send_frame(
                                &response_writer,
                                &ResidentIpcFrame::Error {
                                    request_id: Some(response_request_id),
                                    code: "runtime_unavailable".into(),
                                    message: "the resident IPC request stopped responding".into(),
                                },
                            );
                        }
                        return;
                    }
                }
            }
        });
    if response_spawn.is_err() {
        request.cancellation_token().store(true, Ordering::Release);
        if request.claim_response() {
            let _ = send_frame(
                &writer,
                &ResidentIpcFrame::Error {
                    request_id: Some(request_id),
                    code: "runtime_unavailable".into(),
                    message: "failed to monitor resident IPC request".into(),
                },
            );
        }
    }
}

fn perform_client_handshake(
    pipe: &Pipe,
    browser_origin: &str,
    parent_window: Option<usize>,
) -> Result<()> {
    let mut writer = PipeWriter(Arc::new(pipe.duplicate()?));
    write_frame(
        &mut writer,
        &ResidentIpcFrame::ClientHello(client_hello(browser_origin.to_owned(), parent_window)),
    )?;
    let mut reader = PipeFrameReader::new(Arc::new(pipe.duplicate()?));
    match read_pipe_frame_with_timeout(&mut reader, HANDSHAKE_TIMEOUT)
        .context("wait for resident IPC server hello")?
    {
        ResidentIpcFrame::ServerHello(hello) => validate_server_hello(&hello),
        ResidentIpcFrame::Error { message, .. } => {
            anyhow::bail!("resident IPC handshake rejected: {message}")
        }
        _ => anyhow::bail!("resident IPC server returned an invalid handshake response"),
    }
}

enum BrowserEvent {
    Message(Value),
    DecodeError {
        message: String,
        request_id: Option<String>,
    },
    Oversized {
        length: usize,
        max_length: usize,
    },
    Eof,
    ReadFailed(String),
}

fn read_browser_messages(sender: mpsc::Sender<BrowserEvent>) {
    let stdin = std::io::stdin();
    let mut stdin = stdin.lock();
    loop {
        let event = match read_native_message_or_eof_with_limit::<Value>(
            &mut stdin,
            MAX_NATIVE_REQUEST_BYTES,
        ) {
            Ok(NativeMessage::Message(message)) => BrowserEvent::Message(message),
            Ok(NativeMessage::DecodeError {
                message,
                request_id,
            }) => BrowserEvent::DecodeError {
                message,
                request_id,
            },
            Ok(NativeMessage::Oversized { length, max_length }) => {
                BrowserEvent::Oversized { length, max_length }
            }
            Ok(NativeMessage::Eof) => BrowserEvent::Eof,
            Err(error) => BrowserEvent::ReadFailed(error.to_string()),
        };
        let terminal = matches!(event, BrowserEvent::Eof | BrowserEvent::ReadFailed(_));
        if sender.send(event).is_err() || terminal {
            return;
        }
    }
}

fn forward_browser_messages(pipe: Pipe, receiver: mpsc::Receiver<BrowserEvent>) -> Result<()> {
    let pipe = Arc::new(pipe);
    let mut reader = PipeFrameReader::new(pipe.clone());
    let mut writer = PipeWriter(pipe);
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    let mut pending = HashSet::<String>::new();

    loop {
        match receiver.recv_timeout(Duration::from_millis(10)) {
            Ok(event) => {
                if handle_browser_event(event, &mut writer, &mut stdout, &mut pending)? {
                    return Ok(());
                }
                while let Ok(event) = receiver.try_recv() {
                    if handle_browser_event(event, &mut writer, &mut stdout, &mut pending)? {
                        return Ok(());
                    }
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Ok(());
            }
        }

        while let Some(frame) = reader.try_read_frame()? {
            handle_server_frame(frame, &mut stdout, &mut pending)?;
        }
    }
}

fn handle_browser_event(
    event: BrowserEvent,
    writer: &mut PipeWriter,
    stdout: &mut impl Write,
    pending: &mut HashSet<String>,
) -> Result<bool> {
    match event {
        BrowserEvent::Message(mut message) => {
            let response_request_id = request_id_from_value(&message);
            let (request_id, timeout_ms) = match native_request_metadata(&mut message) {
                Ok(metadata) => metadata,
                Err(error) => {
                    write_native_value(
                        stdout,
                        &runtime_error_value("invalid_request", error.to_string()),
                        response_request_id.as_deref(),
                    )?;
                    return Ok(false);
                }
            };
            if !pending.insert(request_id.clone()) {
                write_native_value(
                    stdout,
                    &runtime_error_value("duplicate_request", "duplicate native request ID"),
                    Some(&request_id),
                )?;
                return Ok(false);
            }
            if let Err(error) = write_frame(
                writer,
                &ResidentIpcFrame::Request {
                    request_id: request_id.clone(),
                    timeout_ms,
                    message,
                },
            ) {
                pending.remove(&request_id);
                return Err(error.context("forward native request to resident app"));
            }
        }
        BrowserEvent::DecodeError {
            message,
            request_id,
        } => write_native_value(
            stdout,
            &runtime_error_value("invalid_request", message),
            request_id.as_deref(),
        )?,
        BrowserEvent::Oversized { length, max_length } => write_native_value(
            stdout,
            &runtime_error_value(
                "invalid_request",
                format!("native message exceeds maximum length: {length} > {max_length}"),
            ),
            None,
        )?,
        BrowserEvent::Eof => return Ok(true),
        BrowserEvent::ReadFailed(message) => {
            return Err(anyhow::anyhow!(message).context("read native browser message"));
        }
    }
    Ok(false)
}

fn handle_server_frame(
    frame: ResidentIpcFrame,
    stdout: &mut impl Write,
    pending: &mut HashSet<String>,
) -> Result<()> {
    match frame {
        ResidentIpcFrame::Response {
            request_id,
            message,
        } => {
            if !pending.remove(&request_id) {
                anyhow::bail!("resident IPC response used an unknown request ID");
            }
            write_native_value(stdout, &message, Some(&request_id))
        }
        ResidentIpcFrame::Error {
            request_id: Some(request_id),
            code,
            message,
        } => {
            if !pending.remove(&request_id) {
                anyhow::bail!("resident IPC error used an unknown request ID");
            }
            write_native_value(
                stdout,
                &runtime_error_value(code, message),
                Some(&request_id),
            )
        }
        ResidentIpcFrame::Error {
            request_id: None,
            code,
            message,
        } => anyhow::bail!("resident IPC server error ({code}): {message}"),
        _ => anyhow::bail!("unexpected resident IPC server frame after handshake"),
    }
}

fn native_request_metadata(message: &mut Value) -> Result<(String, u64)> {
    let fields = message
        .as_object_mut()
        .context("native request must be a JSON object")?;
    let request_id = fields
        .remove("requestId")
        .and_then(|value| value.as_str().map(str::to_owned))
        .context("native request is missing a request ID")?;
    let timeout_ms = fields
        .remove("requestTimeoutMs")
        .map(|value| {
            value
                .as_u64()
                .context("native request timeout must be an unsigned integer")
        })
        .transpose()?
        .unwrap_or(RESIDENT_IPC_DEFAULT_TIMEOUT_MS);
    validate_request(&request_id, timeout_ms)?;
    Ok((request_id, timeout_ms))
}

fn request_id_from_value(message: &Value) -> Option<String> {
    message
        .get("requestId")
        .and_then(Value::as_str)
        .map(str::to_owned)
}

fn runtime_error_value(code: impl Into<String>, message: impl Into<String>) -> Value {
    json!({
        "type": "error",
        "code": code.into(),
        "message": message.into(),
    })
}

fn write_native_value(
    writer: &mut impl Write,
    message: &Value,
    request_id: Option<&str>,
) -> Result<()> {
    let mut payload = encode_native_value(message, request_id)?;
    if payload.len() > MAX_NATIVE_RESPONSE_BYTES {
        let error = runtime_error_value(
            "response_too_large",
            "native response exceeds Chrome's 1 MiB limit",
        );
        payload = encode_native_value(&error, request_id)?;
        if payload.len() > MAX_NATIVE_RESPONSE_BYTES {
            payload = encode_native_value(&error, None)?;
        }
    }
    let length = u32::try_from(payload.len()).context("native response length overflow")?;
    writer.write_all(&length.to_le_bytes())?;
    writer.write_all(&payload)?;
    writer.flush().context("flush native response")
}

fn encode_native_value(message: &Value, request_id: Option<&str>) -> Result<Vec<u8>> {
    match request_id {
        Some(request_id) => {
            if !message.is_object() {
                anyhow::bail!("native response must be a JSON object");
            }
            serde_json::to_vec(&CorrelatedNativeResponse {
                message,
                request_id,
            })
        }
        None => serde_json::to_vec(message),
    }
    .context("encode native response")
}

#[derive(Serialize)]
struct CorrelatedNativeResponse<'a> {
    #[serde(flatten)]
    message: &'a Value,
    #[serde(rename = "requestId")]
    request_id: &'a str,
}

fn send_frame(writer: &Arc<Mutex<PipeWriter>>, frame: &ResidentIpcFrame) -> Result<()> {
    let mut writer = writer.lock().unwrap_or_else(|error| error.into_inner());
    write_frame(&mut *writer, frame)
}

fn send_runtime_response(
    writer: &Arc<Mutex<PipeWriter>>,
    request_id: String,
    message: Value,
) -> Result<()> {
    if encode_native_value(&message, Some(&request_id))?.len() > MAX_NATIVE_RESPONSE_BYTES {
        return send_frame(
            writer,
            &ResidentIpcFrame::Error {
                request_id: Some(request_id),
                code: "response_too_large".into(),
                message: "native response exceeds Chrome's 1 MiB limit".into(),
            },
        );
    }
    send_frame(
        writer,
        &ResidentIpcFrame::Response {
            request_id,
            message,
        },
    )
}

fn create_server_pipe(pipe_name: &[u16], sid_string: &str, first: bool) -> Result<Pipe> {
    let descriptor = SecurityDescriptor::for_sid(sid_string)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let mut open_mode = PIPE_ACCESS_DUPLEX;
    if first {
        open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
    }
    let handle = unsafe {
        CreateNamedPipeW(
            pipe_name.as_ptr(),
            open_mode,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_UNLIMITED_INSTANCES,
            PIPE_BUFFER_BYTES,
            PIPE_BUFFER_BYTES,
            0,
            &attributes,
        )
    };
    Pipe::from_created(handle).context("CreateNamedPipeW failed")
}

fn connect_server_pipe(pipe: &Pipe) -> Result<()> {
    if unsafe { ConnectNamedPipe(pipe.handle(), null_mut()) } != 0 {
        return Ok(());
    }
    let error = unsafe { GetLastError() };
    if error == ERROR_PIPE_CONNECTED {
        Ok(())
    } else {
        Err(std::io::Error::from_raw_os_error(error as i32).into())
    }
}

fn open_client_pipe(pipe_name: &[u16]) -> Result<Pipe> {
    let flags = SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION | SECURITY_EFFECTIVE_ONLY;
    let mut handle = unsafe {
        CreateFileW(
            pipe_name.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            null(),
            OPEN_EXISTING,
            flags,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE && unsafe { GetLastError() } == ERROR_PIPE_BUSY {
        if unsafe { WaitNamedPipeW(pipe_name.as_ptr(), PIPE_CONNECT_WAIT_MS) } == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        handle = unsafe {
            CreateFileW(
                pipe_name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                null(),
                OPEN_EXISTING,
                flags,
                null_mut(),
            )
        };
    }
    Pipe::from_created(handle).context("CreateFileW for resident IPC pipe failed")
}

fn verify_pipe_client(pipe: &Pipe, expected_sid: &[u8]) -> Result<()> {
    let mut process_id = 0;
    check_win32(
        unsafe { GetNamedPipeClientProcessId(pipe.handle(), &mut process_id) },
        "GetNamedPipeClientProcessId",
    )?;
    verify_process_sid(process_id, expected_sid)
}

fn verify_pipe_server(pipe: &Pipe, expected_sid: &[u8]) -> Result<()> {
    let mut process_id = 0;
    check_win32(
        unsafe { GetNamedPipeServerProcessId(pipe.handle(), &mut process_id) },
        "GetNamedPipeServerProcessId",
    )?;
    verify_process_sid(process_id, expected_sid)
}

fn verify_process_sid(process_id: u32, expected_sid: &[u8]) -> Result<()> {
    let actual_sid = process_user_sid(process_id)?;
    if actual_sid != expected_sid {
        anyhow::bail!("resident IPC peer belongs to a different Windows user");
    }
    Ok(())
}

fn resolve_request_parent_window(
    requested_parent_window: Option<usize>,
    expected_sid: &[u8],
) -> Option<usize> {
    requested_parent_window
        .filter(|window| window_belongs_to_sid(*window, expected_sid))
        .or_else(|| {
            let window = unsafe { GetForegroundWindow() } as usize;
            (window != 0 && window_belongs_to_sid(window, expected_sid)).then_some(window)
        })
}

fn window_belongs_to_sid(window: usize, expected_sid: &[u8]) -> bool {
    let mut process_id = 0;
    let thread_id =
        unsafe { GetWindowThreadProcessId(window as *mut std::ffi::c_void, &mut process_id) };
    thread_id != 0 && process_id != 0 && verify_process_sid(process_id, expected_sid).is_ok()
}

struct ProcessIdentity {
    sid: Vec<u8>,
    sid_string: String,
}

impl ProcessIdentity {
    fn current() -> Result<Self> {
        let sid = token_user_sid(unsafe { GetCurrentProcess() }, false)?;
        let sid_string = sid_to_string(&sid)?;
        Ok(Self { sid, sid_string })
    }
}

fn process_user_sid(process_id: u32) -> Result<Vec<u8>> {
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    if process.is_null() {
        return Err(std::io::Error::last_os_error().into());
    }
    let result = token_user_sid(process, true);
    result
}

fn token_user_sid(process: HANDLE, close_process: bool) -> Result<Vec<u8>> {
    let process = ProcessHandleGuard {
        handle: process,
        close: close_process,
    };
    let mut token = null_mut();
    check_win32(
        unsafe { OpenProcessToken(process.handle, TOKEN_QUERY, &mut token) },
        "OpenProcessToken",
    )?;
    let token = HandleGuard(token);

    let mut token_type = 0_i32;
    let mut returned = 0;
    check_win32(
        unsafe {
            GetTokenInformation(
                token.0,
                TokenType,
                (&mut token_type as *mut i32).cast(),
                size_of::<i32>() as u32,
                &mut returned,
            )
        },
        "GetTokenInformation(TokenType)",
    )?;
    if token_type != TokenPrimary {
        anyhow::bail!("resident IPC peer does not have a primary process token");
    }

    let mut required = 0;
    unsafe {
        GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut required);
    }
    if required < size_of::<TOKEN_USER>() as u32 {
        return Err(std::io::Error::last_os_error())
            .context("GetTokenInformation(TokenUser) did not report a valid size");
    }
    let words = (required as usize).div_ceil(size_of::<usize>());
    let mut storage = vec![0_usize; words];
    check_win32(
        unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                storage.as_mut_ptr().cast(),
                required,
                &mut returned,
            )
        },
        "GetTokenInformation(TokenUser)",
    )?;
    let user = unsafe { &*(storage.as_ptr().cast::<TOKEN_USER>()) };
    copy_sid(user.User.Sid)
}

fn copy_sid(sid: PSID) -> Result<Vec<u8>> {
    let length = unsafe { GetLengthSid(sid) };
    if length == 0 {
        return Err(std::io::Error::last_os_error()).context("GetLengthSid failed");
    }
    let mut copied = vec![0_u8; length as usize];
    check_win32(
        unsafe { CopySid(length, copied.as_mut_ptr().cast(), sid) },
        "CopySid",
    )?;
    Ok(copied)
}

fn sid_to_string(sid: &[u8]) -> Result<String> {
    let mut value = null_mut();
    check_win32(
        unsafe { ConvertSidToStringSidW(sid.as_ptr() as PSID, &mut value) },
        "ConvertSidToStringSidW",
    )?;
    let value = LocalAllocation(value.cast());
    let mut length = 0;
    while unsafe { *value.0.cast::<u16>().add(length) } != 0 {
        length += 1;
    }
    String::from_utf16(unsafe { std::slice::from_raw_parts(value.0.cast::<u16>(), length) })
        .context("Windows SID string is not valid UTF-16")
}

struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

impl SecurityDescriptor {
    fn for_sid(sid: &str) -> Result<Self> {
        let sddl = wide_nul(&format!("D:P(A;;GA;;;SY)(A;;GA;;;{sid})"));
        let mut descriptor = null_mut();
        check_win32(
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.as_ptr(),
                    SDDL_REVISION_1,
                    &mut descriptor,
                    null_mut(),
                )
            },
            "ConvertStringSecurityDescriptorToSecurityDescriptorW",
        )?;
        Ok(Self(descriptor))
    }
}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

struct LocalAllocation(*mut c_void);

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0);
            }
        }
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

struct ProcessHandleGuard {
    handle: HANDLE,
    close: bool,
}

impl Drop for ProcessHandleGuard {
    fn drop(&mut self) {
        if self.close && !self.handle.is_null() && self.handle != INVALID_HANDLE_VALUE {
            unsafe {
                CloseHandle(self.handle);
            }
        }
    }
}

struct Pipe(HANDLE);

unsafe impl Send for Pipe {}
unsafe impl Sync for Pipe {}

impl Pipe {
    fn from_created(handle: HANDLE) -> Result<Self> {
        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            Err(std::io::Error::last_os_error().into())
        } else {
            Ok(Self(handle))
        }
    }

    fn handle(&self) -> HANDLE {
        self.0
    }

    fn duplicate(&self) -> Result<Self> {
        let current = unsafe { GetCurrentProcess() };
        let mut duplicate = null_mut();
        check_win32(
            unsafe {
                windows_sys::Win32::Foundation::DuplicateHandle(
                    current,
                    self.0,
                    current,
                    &mut duplicate,
                    0,
                    0,
                    windows_sys::Win32::Foundation::DUPLICATE_SAME_ACCESS,
                )
            },
            "DuplicateHandle",
        )?;
        Ok(Self(duplicate))
    }
}

impl Drop for Pipe {
    fn drop(&mut self) {
        unsafe {
            DisconnectNamedPipe(self.0);
            CloseHandle(self.0);
        }
    }
}

struct PipeReader(Arc<Pipe>);

impl Read for PipeReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        let length = buffer.len().min(u32::MAX as usize) as u32;
        let mut read = 0;
        if unsafe {
            ReadFile(
                self.0.handle(),
                buffer.as_mut_ptr(),
                length,
                &mut read,
                null_mut(),
            )
        } == 0
        {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(read as usize)
        }
    }
}

struct PipeFrameReader {
    pipe: Arc<Pipe>,
    buffered: Vec<u8>,
}

impl PipeFrameReader {
    fn new(pipe: Arc<Pipe>) -> Self {
        Self {
            pipe,
            buffered: Vec::new(),
        }
    }

    fn try_read_frame(&mut self) -> Result<Option<ResidentIpcFrame>> {
        if let Some(frame) = self.try_decode_buffered_frame()? {
            return Ok(Some(frame));
        }

        let available = pipe_available_bytes(&self.pipe)?;
        if available == 0 {
            return Ok(None);
        }
        let chunk_length = available.min(PIPE_BUFFER_BYTES) as usize;
        let mut chunk = vec![0_u8; chunk_length];
        let read = PipeReader(self.pipe.clone())
            .read(&mut chunk)
            .context("read available resident IPC frame bytes")?;
        if read == 0 {
            anyhow::bail!("resident IPC pipe closed while reading a frame");
        }
        chunk.truncate(read);
        self.buffered.extend_from_slice(&chunk);
        self.try_decode_buffered_frame()
    }

    fn try_decode_buffered_frame(&mut self) -> Result<Option<ResidentIpcFrame>> {
        if self.buffered.len() < 4 {
            return Ok(None);
        }
        let payload_length = u32::from_le_bytes(
            self.buffered[..4]
                .try_into()
                .expect("resident IPC prefix has four bytes"),
        ) as usize;
        if payload_length > super::RESIDENT_IPC_MAX_FRAME_BYTES {
            anyhow::bail!(
                "resident IPC frame exceeds maximum length: {payload_length} > {}",
                super::RESIDENT_IPC_MAX_FRAME_BYTES
            );
        }
        let frame_length = 4 + payload_length;
        if self.buffered.len() < frame_length {
            return Ok(None);
        }
        let frame = serde_json::from_slice(&self.buffered[4..frame_length])
            .context("failed to decode resident IPC frame")?;
        self.buffered.drain(..frame_length);
        Ok(Some(frame))
    }
}

struct PipeWriter(Arc<Pipe>);

impl Write for PipeWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        let length = buffer.len().min(u32::MAX as usize) as u32;
        let mut written = 0;
        if unsafe {
            WriteFile(
                self.0.handle(),
                buffer.as_ptr(),
                length,
                &mut written,
                null_mut(),
            )
        } == 0
        {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(written as usize)
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn pipe_available_bytes(pipe: &Pipe) -> Result<u32> {
    let mut available = 0;
    check_win32(
        unsafe {
            PeekNamedPipe(
                pipe.handle(),
                null_mut(),
                0,
                null_mut(),
                &mut available,
                null_mut(),
            )
        },
        "PeekNamedPipe",
    )?;
    Ok(available)
}

fn read_pipe_frame_with_timeout(
    reader: &mut PipeFrameReader,
    timeout: Duration,
) -> Result<ResidentIpcFrame> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(frame) = reader.try_read_frame()? {
            return Ok(frame);
        }
        if Instant::now() >= deadline {
            anyhow::bail!("resident IPC handshake timed out");
        }
        std::thread::sleep(REQUEST_POLL_INTERVAL);
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
    use std::io::{Cursor, Read as _};
    use std::sync::atomic::AtomicUsize;

    use super::*;
    use crate::resident_ipc::read_frame;

    const EXTENSION_ORIGIN: &str = "chrome-extension://kblgblkjghklighdgmejjfondchkjcgf/";

    #[test]
    fn unavailable_resident_app_returns_a_correlated_native_error() {
        let request = serde_json::to_vec(&json!({
            "version": 1,
            "requestId": "native-startup-1",
            "requestTimeoutMs": 30_000,
            "command": { "type": "get_session_state" }
        }))
        .expect("encode native request");
        let mut input = Vec::with_capacity(4 + request.len());
        input.extend_from_slice(&(request.len() as u32).to_le_bytes());
        input.extend_from_slice(&request);
        let mut output = Vec::new();

        write_startup_failure_to(
            &mut Cursor::new(input),
            &mut output,
            "resident_unavailable",
            "start the VaultKern app",
        )
        .expect("write startup failure");

        let mut output = Cursor::new(output);
        let mut length = [0_u8; 4];
        output
            .read_exact(&mut length)
            .expect("read response length");
        let mut payload = vec![0_u8; u32::from_le_bytes(length) as usize];
        output
            .read_exact(&mut payload)
            .expect("read response payload");
        let response: Value = serde_json::from_slice(&payload).expect("decode native response");
        assert_eq!(response["type"], "error");
        assert_eq!(response["code"], "resident_unavailable");
        assert_eq!(response["requestId"], "native-startup-1");
    }

    #[test]
    fn oversized_request_id_cannot_make_the_recoverable_error_exceed_chromes_limit() {
        let request_id = "r".repeat(MAX_NATIVE_RESPONSE_BYTES);
        let mut output = Vec::new();

        write_native_value(
            &mut output,
            &runtime_error_value("invalid_request", "invalid request ID"),
            Some(&request_id),
        )
        .expect("write bounded native error");

        assert!(output.len() <= 4 + MAX_NATIVE_RESPONSE_BYTES);
        let mut output = Cursor::new(output);
        let mut length = [0_u8; 4];
        output
            .read_exact(&mut length)
            .expect("read response length");
        let mut payload = vec![0_u8; u32::from_le_bytes(length) as usize];
        output
            .read_exact(&mut payload)
            .expect("read response payload");
        let response: Value = serde_json::from_slice(&payload).expect("decode native response");
        assert_eq!(response["type"], "error");
        assert_eq!(response["code"], "response_too_large");
        assert!(response.get("requestId").is_none());
    }

    #[test]
    fn authenticated_pipe_round_trips_and_honors_cancellation_and_timeout() {
        let observed_cancellations = Arc::new(AtomicUsize::new(0));
        let handler_cancellations = observed_cancellations.clone();
        let server = start_windows_resident_ipc_server(Arc::new(
            move |message, cancelled, _parent_window| match message["command"]["type"].as_str() {
                Some("get_session_state") => {
                    json!({ "type": "session_state", "unlocked": false })
                }
                Some("echo_blob") => json!({
                    "type": "blob_echo",
                    "payload": message["command"]["payload"].clone(),
                }),
                Some("oversized_response") => json!({
                    "type": "oversized_response",
                    "payload": "A".repeat(MAX_NATIVE_RESPONSE_BYTES),
                }),
                Some("block_until_cancelled") => {
                    while !cancelled.load(Ordering::Acquire) {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    handler_cancellations.fetch_add(1, Ordering::AcqRel);
                    json!({ "type": "saved" })
                }
                command => panic!("unexpected test command: {command:?}"),
            },
        ))
        .expect("start resident IPC server");
        let identity = ProcessIdentity::current().expect("current identity");
        let pipe_name = wide_nul(&format!("{PIPE_PREFIX}{}", identity.sid_string));
        let pipe = open_client_pipe(&pipe_name).expect("connect resident IPC client");
        verify_pipe_server(&pipe, &identity.sid).expect("verify resident IPC server");
        perform_client_handshake(&pipe, EXTENSION_ORIGIN, None).expect("negotiate resident IPC");
        let pipe = Arc::new(pipe);
        let mut writer = PipeWriter(pipe.clone());
        let mut reader = PipeReader(pipe);

        write_frame(
            &mut writer,
            &ResidentIpcFrame::Request {
                request_id: "native-test-1".into(),
                timeout_ms: 5_000,
                message: json!({
                    "version": 1,
                    "command": { "type": "get_session_state" }
                }),
            },
        )
        .expect("send resident IPC request");

        let response = read_frame(&mut reader)
            .expect("read resident IPC response")
            .expect("response before EOF");
        match response {
            ResidentIpcFrame::Response {
                request_id,
                message,
            } => {
                assert_eq!(request_id, "native-test-1");
                assert_eq!(message["type"], "session_state");
            }
            _ => panic!("expected correlated response"),
        }

        let large_blob = "A".repeat((PIPE_BUFFER_BYTES as usize) * 4);
        write_frame(
            &mut writer,
            &ResidentIpcFrame::Request {
                request_id: "native-large-1".into(),
                timeout_ms: 5_000,
                message: json!({
                    "version": 1,
                    "command": {
                        "type": "echo_blob",
                        "payload": large_blob.clone(),
                    }
                }),
            },
        )
        .expect("send resident IPC request larger than the pipe buffer");
        let response = read_frame(&mut reader)
            .expect("read large resident IPC response")
            .expect("large response before EOF");
        match response {
            ResidentIpcFrame::Response {
                request_id,
                message,
            } => {
                assert_eq!(request_id, "native-large-1");
                assert_eq!(message["type"], "blob_echo");
                assert_eq!(
                    message["payload"].as_str().map(str::len),
                    Some(large_blob.len())
                );
            }
            _ => panic!("expected correlated large response"),
        }

        write_frame(
            &mut writer,
            &ResidentIpcFrame::Request {
                request_id: "native-oversized-response-1".into(),
                timeout_ms: 5_000,
                message: json!({
                    "version": 1,
                    "command": { "type": "oversized_response" }
                }),
            },
        )
        .expect("send resident IPC request with an oversized response");
        assert_request_error(
            read_frame(&mut reader)
                .expect("read oversized response error")
                .expect("oversized response error before EOF"),
            "native-oversized-response-1",
            "response_too_large",
        );

        write_frame(
            &mut writer,
            &ResidentIpcFrame::Request {
                request_id: "native-cancel-1".into(),
                timeout_ms: 5_000,
                message: json!({
                    "version": 1,
                    "command": { "type": "block_until_cancelled" }
                }),
            },
        )
        .expect("send cancellable resident IPC request");
        write_frame(
            &mut writer,
            &ResidentIpcFrame::Cancel {
                request_id: "native-cancel-1".into(),
            },
        )
        .expect("cancel resident IPC request");
        assert_request_error(
            read_frame(&mut reader)
                .expect("read cancellation response")
                .expect("cancellation response before EOF"),
            "native-cancel-1",
            "request_cancelled",
        );

        write_frame(
            &mut writer,
            &ResidentIpcFrame::Request {
                request_id: "native-timeout-1".into(),
                timeout_ms: 50,
                message: json!({
                    "version": 1,
                    "command": { "type": "block_until_cancelled" }
                }),
            },
        )
        .expect("send timing out resident IPC request");
        assert_request_error(
            read_frame(&mut reader)
                .expect("read timeout response")
                .expect("timeout response before EOF"),
            "native-timeout-1",
            "request_timeout",
        );

        let deadline = Instant::now() + Duration::from_secs(2);
        while observed_cancellations.load(Ordering::Acquire) != 2 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(observed_cancellations.load(Ordering::Acquire), 2);

        drop(server);
    }

    fn assert_request_error(
        frame: ResidentIpcFrame,
        expected_request_id: &str,
        expected_code: &str,
    ) {
        match frame {
            ResidentIpcFrame::Error {
                request_id: Some(request_id),
                code,
                ..
            } => {
                assert_eq!(request_id, expected_request_id);
                assert_eq!(code, expected_code);
            }
            _ => panic!("expected correlated resident IPC error"),
        }
    }
}
