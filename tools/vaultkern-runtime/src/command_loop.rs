use std::io::{Read, Write};
use std::panic::{AssertUnwindSafe, catch_unwind};

use anyhow::{Context, Result};
use vaultkern_runtime_protocol::{ErrorDto, ProtocolEnvelope, RuntimeCommand, RuntimeResponse};
use zeroize::Zeroizing;

use crate::{Runtime, RuntimeProtocolDispatch, RuntimeProtocolSession};

pub(crate) const MAX_NATIVE_REQUEST_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const MAX_NATIVE_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_CHUNKED_NATIVE_RESPONSE_BYTES: usize = 64 * 1024 * 1024;
const NATIVE_RESPONSE_CHUNK_BYTES: usize = 384 * 1024;
const MAX_NATIVE_REQUEST_ID_BYTES: usize = 256;

pub fn run_stdio_loop(runtime: Runtime) -> Result<()> {
    run_stdio_loop_with_session(runtime, RuntimeProtocolSession::legacy_native_host())
}

pub fn run_browser_stdio_loop(runtime: Runtime) -> Result<()> {
    run_stdio_loop_with_session(runtime, RuntimeProtocolSession::browser_extension())
}

fn run_stdio_loop_with_session(
    runtime: Runtime,
    protocol_session: RuntimeProtocolSession,
) -> Result<()> {
    install_redacted_panic_hook();
    configure_stdio_for_native_messaging()?;

    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut stdin = stdin.lock();
    let mut stdout = stdout.lock();

    run_loop_with_io_with_session(runtime, protocol_session, &mut stdin, &mut stdout)
}

pub fn install_redacted_panic_hook() {
    static INSTALL: std::sync::Once = std::sync::Once::new();
    INSTALL.call_once(|| {
        std::panic::set_hook(Box::new(|panic| {
            if let Some(location) = panic.location() {
                eprintln!(
                    "VaultKern runtime panicked at {}:{}:{}",
                    location.file(),
                    location.line(),
                    location.column()
                );
            } else {
                eprintln!("VaultKern runtime panicked");
            }
        }));
    });
}

#[cfg(test)]
fn run_loop_with_io(
    runtime: Runtime,
    stdin: &mut impl Read,
    stdout: &mut impl Write,
) -> Result<()> {
    run_loop_with_io_with_limit(
        runtime,
        RuntimeProtocolSession::legacy_native_host(),
        stdin,
        stdout,
        MAX_NATIVE_REQUEST_BYTES,
    )
}

fn run_loop_with_io_with_session(
    runtime: Runtime,
    protocol_session: RuntimeProtocolSession,
    stdin: &mut impl Read,
    stdout: &mut impl Write,
) -> Result<()> {
    run_loop_with_io_with_limit(
        runtime,
        protocol_session,
        stdin,
        stdout,
        MAX_NATIVE_REQUEST_BYTES,
    )
}

fn run_loop_with_io_with_limit(
    mut runtime: Runtime,
    mut protocol_session: RuntimeProtocolSession,
    stdin: &mut impl Read,
    stdout: &mut impl Write,
    max_message_bytes: usize,
) -> Result<()> {
    loop {
        match read_native_message_or_eof_with_limit::<ProtocolEnvelope>(stdin, max_message_bytes)? {
            NativeMessage::Eof => return Ok(()),
            NativeMessage::Message(envelope) => {
                let request_id = match envelope.request_id {
                    Some(request_id) if request_id.len() <= MAX_NATIVE_REQUEST_ID_BYTES => {
                        Some(request_id)
                    }
                    Some(_) => {
                        write_native_message(
                            stdout,
                            &invalid_native_message_response(
                                "native request id exceeds the framing limit".to_owned(),
                            ),
                            None,
                        )?;
                        continue;
                    }
                    None => None,
                };
                if envelope.version != vaultkern_runtime_protocol::PROTOCOL_VERSION {
                    write_native_message(
                        stdout,
                        &RuntimeResponse::Error(ErrorDto {
                            code: "unsupported_version".into(),
                            message: format!(
                                "unsupported runtime protocol version: {}",
                                envelope.version
                            ),
                        }),
                        request_id.as_deref(),
                    )?;
                    continue;
                }
                let command = match protocol_session.accept(envelope.command) {
                    RuntimeProtocolDispatch::Respond(response) => {
                        write_native_message(stdout, &response, request_id.as_deref())?;
                        continue;
                    }
                    RuntimeProtocolDispatch::Dispatch(command) => command,
                };
                let outcome = handle_command_response(&mut runtime, command);
                #[cfg(debug_assertions)]
                maybe_abort_after_autofill_source_commit(&outcome.response);
                write_native_message(stdout, &outcome.response, request_id.as_deref())?;
                if outcome.fatal {
                    return Ok(());
                }
            }
            NativeMessage::DecodeError {
                message,
                request_id,
            } => {
                write_native_message(
                    stdout,
                    &invalid_native_message_response(message),
                    request_id.as_deref(),
                )?;
            }
            NativeMessage::Oversized { length, max_length } => {
                write_native_message(
                    stdout,
                    &oversized_native_message_response(length, max_length),
                    None,
                )?;
                return Ok(());
            }
        };
    }
}

struct CommandOutcome {
    response: RuntimeResponse,
    fatal: bool,
}

fn handle_command_response(runtime: &mut Runtime, command: RuntimeCommand) -> CommandOutcome {
    command_response_from_result(|| runtime.handle(command))
}

#[cfg(debug_assertions)]
const AUTOFILL_SOURCE_COMMIT_CRASH_MARKER_ENV: &str =
    "VAULTKERN_TEST_CRASH_AFTER_AUTOFILL_SOURCE_COMMIT_MARKER";

#[cfg(any(debug_assertions, test))]
fn is_committed_autofill_source_response(response: &RuntimeResponse) -> bool {
    matches!(
        response,
        RuntimeResponse::AutofillPersistResult(result)
            if matches!(
                result.outcome,
                vaultkern_runtime_protocol::AutofillPersistOutcomeDto::Durable {
                    disposition: vaultkern_runtime_protocol::AutofillPersistDispositionDto::Committed,
                    durability: vaultkern_runtime_protocol::AutofillPersistDurabilityDto::Source,
                    ..
                }
            )
    )
}

#[cfg(any(debug_assertions, test))]
fn claim_autofill_source_commit_crash_marker(
    response: &RuntimeResponse,
    marker_path: &std::path::Path,
) -> std::io::Result<bool> {
    let RuntimeResponse::AutofillPersistResult(result) = response else {
        return Ok(false);
    };
    if !is_committed_autofill_source_response(response) {
        return Ok(false);
    }

    let mut marker = match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(marker_path)
    {
        Ok(marker) => marker,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => return Ok(false),
        Err(error) => return Err(error),
    };
    writeln!(marker, "{}:{}", result.transaction_id, result.operation_id)?;
    marker.sync_all()?;
    Ok(true)
}

#[cfg(debug_assertions)]
fn maybe_abort_after_autofill_source_commit(response: &RuntimeResponse) {
    let Some(marker_path) = std::env::var_os(AUTOFILL_SOURCE_COMMIT_CRASH_MARKER_ENV) else {
        return;
    };
    if claim_autofill_source_commit_crash_marker(response, std::path::Path::new(&marker_path))
        .unwrap_or(false)
    {
        std::process::abort();
    }
}

fn command_response_from_result(run: impl FnOnce() -> Result<RuntimeResponse>) -> CommandOutcome {
    match catch_unwind(AssertUnwindSafe(run)) {
        Ok(Ok(response)) => CommandOutcome {
            response,
            fatal: false,
        },
        Ok(Err(error)) => CommandOutcome {
            response: RuntimeResponse::Error(ErrorDto {
                code: "invalid_request".into(),
                message: format_error_chain(&error),
            }),
            fatal: false,
        },
        Err(_payload) => CommandOutcome {
            response: RuntimeResponse::Error(ErrorDto {
                code: "panic".into(),
                message: "runtime command panicked".into(),
            }),
            fatal: true,
        },
    }
}

pub(crate) fn format_error_chain(error: &anyhow::Error) -> String {
    error
        .chain()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(": ")
}

#[derive(Debug, PartialEq)]
pub(crate) enum NativeMessage<T> {
    Eof,
    Message(T),
    DecodeError {
        message: String,
        request_id: Option<String>,
    },
    Oversized {
        length: usize,
        max_length: usize,
    },
}

pub(crate) fn read_native_message_or_eof_with_limit<T: serde::de::DeserializeOwned>(
    reader: &mut impl Read,
    max_message_bytes: usize,
) -> Result<NativeMessage<T>> {
    let mut length = [0_u8; 4];
    let mut read = 0;
    while read < length.len() {
        let count = reader
            .read(&mut length[read..])
            .context("failed to read message length")?;
        if count == 0 {
            if read == 0 {
                return Ok(NativeMessage::Eof);
            }
            anyhow::bail!("failed to read message length");
        }
        read += count;
    }

    let length = u32::from_le_bytes(length) as usize;
    if length > max_message_bytes {
        return Ok(NativeMessage::Oversized {
            length,
            max_length: max_message_bytes,
        });
    }
    let mut payload = Zeroizing::new(vec![0_u8; length]);
    reader
        .read_exact(&mut payload)
        .context("failed to read message payload")?;
    match serde_json::from_slice(&payload) {
        Ok(message) => Ok(NativeMessage::Message(message)),
        Err(error) => Ok(NativeMessage::DecodeError {
            message: format!("failed to decode native message: {error}"),
            request_id: request_id_from_native_payload(&payload),
        }),
    }
}

fn oversized_native_message_response(length: usize, max_length: usize) -> RuntimeResponse {
    RuntimeResponse::Error(ErrorDto {
        code: "invalid_request".into(),
        message: format!("native message exceeds maximum length: {length} > {max_length}"),
    })
}

fn invalid_native_message_response(message: String) -> RuntimeResponse {
    RuntimeResponse::Error(ErrorDto {
        code: "invalid_request".into(),
        message,
    })
}

fn request_id_from_native_payload(payload: &[u8]) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct RequestIdOnly {
        #[serde(default, rename = "requestId")]
        request_id: Option<String>,
    }

    serde_json::from_slice::<RequestIdOnly>(payload)
        .ok()?
        .request_id
        .filter(|request_id| request_id.len() <= MAX_NATIVE_REQUEST_ID_BYTES)
}

pub(crate) fn write_native_message(
    writer: &mut impl Write,
    response: &RuntimeResponse,
    request_id: Option<&str>,
) -> Result<()> {
    let mut payload =
        encode_native_response(response, request_id).context("failed to encode native message")?;
    if payload.len() > MAX_NATIVE_RESPONSE_BYTES {
        let oversized = RuntimeResponse::Error(ErrorDto {
            code: "response_too_large".into(),
            message: "native response exceeds Chrome's 1 MiB limit".into(),
        });
        payload = encode_native_response(&oversized, request_id)
            .context("failed to encode oversized native response error")?;
        if payload.len() > MAX_NATIVE_RESPONSE_BYTES {
            payload = encode_native_response(&oversized, None)
                .context("failed to encode uncorrelated oversized native response error")?;
        }
    }
    write_native_payload(writer, &payload)
}

pub(crate) fn write_chunked_native_message(
    writer: &mut impl Write,
    response: &RuntimeResponse,
    request_id: &str,
) -> Result<()> {
    #[derive(serde::Serialize)]
    struct NativeResponseChunk<'a> {
        #[serde(rename = "type")]
        message_type: &'static str,
        #[serde(rename = "requestId")]
        request_id: &'a str,
        #[serde(rename = "chunkIndex")]
        chunk_index: u32,
        #[serde(rename = "chunkCount")]
        chunk_count: u32,
        data: &'a str,
    }

    let payload = encode_native_response(response, Some(request_id))
        .context("failed to encode native message")?;
    if payload.len() <= MAX_NATIVE_RESPONSE_BYTES {
        return write_native_payload(writer, &payload);
    }
    if payload.len() > MAX_CHUNKED_NATIVE_RESPONSE_BYTES {
        return write_native_message(
            writer,
            &RuntimeResponse::Error(ErrorDto {
                code: "response_too_large".into(),
                message: "native response exceeds the 64 MiB chunked transport limit".into(),
            }),
            Some(request_id),
        );
    }

    let payload_text = std::str::from_utf8(&payload).context("native response is not UTF-8")?;
    let mut ranges = Vec::new();
    let mut start = 0;
    while start < payload_text.len() {
        let mut end = (start + NATIVE_RESPONSE_CHUNK_BYTES).min(payload_text.len());
        while end > start && !payload_text.is_char_boundary(end) {
            end -= 1;
        }
        if end == start {
            anyhow::bail!("native response chunk boundary did not advance");
        }
        ranges.push((start, end));
        start = end;
    }
    let chunk_count =
        u32::try_from(ranges.len()).context("native response chunk count overflow")?;
    for (chunk_index, (start, end)) in ranges.into_iter().enumerate() {
        let chunk = encode_zeroizing_json(&NativeResponseChunk {
            message_type: "native_response_chunk",
            request_id,
            chunk_index: u32::try_from(chunk_index)
                .context("native response chunk index overflow")?,
            chunk_count,
            data: &payload_text[start..end],
        })
        .context("encode native response chunk")?;
        if chunk.len() > MAX_NATIVE_RESPONSE_BYTES {
            anyhow::bail!("encoded native response chunk exceeds Chrome's 1 MiB limit");
        }
        write_native_payload(writer, &chunk)?;
    }
    Ok(())
}

fn write_native_payload(writer: &mut impl Write, payload: &[u8]) -> Result<()> {
    let length = native_message_length_prefix(payload.len())?;
    writer
        .write_all(&length)
        .context("failed to write message length")?;
    writer
        .write_all(payload)
        .context("failed to write message payload")?;
    writer.flush().context("failed to flush native message")
}

fn native_message_length_prefix(length: usize) -> Result<[u8; 4]> {
    let length = u32::try_from(length).context("native response exceeds the framing limit")?;
    Ok(length.to_le_bytes())
}

pub(crate) fn encode_native_response(
    response: &RuntimeResponse,
    request_id: Option<&str>,
) -> Result<Zeroizing<Vec<u8>>> {
    #[derive(serde::Serialize)]
    struct ResponseWithRequestId<'a> {
        #[serde(flatten)]
        response: &'a RuntimeResponse,
        #[serde(rename = "requestId")]
        request_id: &'a str,
    }

    match request_id {
        Some(request_id) => encode_zeroizing_json(&ResponseWithRequestId {
            response,
            request_id,
        }),
        None => encode_zeroizing_json(response),
    }
    .context("failed to encode native response")
}

pub fn encode_zeroizing_json<T: serde::Serialize>(value: &T) -> Result<Zeroizing<Vec<u8>>> {
    #[derive(Default)]
    struct SerializedLength {
        bytes: usize,
    }

    impl Write for SerializedLength {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.bytes = self
                .bytes
                .checked_add(buffer.len())
                .ok_or_else(|| std::io::Error::other("serialized JSON length overflow"))?;
            Ok(buffer.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let mut length = SerializedLength::default();
    serde_json::to_writer(&mut length, value).context("measure JSON payload")?;

    let mut payload = Zeroizing::new(Vec::with_capacity(length.bytes));
    serde_json::to_writer(&mut *payload, value).context("encode JSON payload")?;
    if payload.len() != length.bytes {
        anyhow::bail!(
            "serialized JSON length changed between measurement and encoding: {} != {}",
            payload.len(),
            length.bytes
        );
    }
    Ok(payload)
}

#[cfg(not(windows))]
pub(crate) fn configure_stdio_for_native_messaging() -> Result<()> {
    Ok(())
}

#[cfg(windows)]
pub(crate) fn configure_stdio_for_native_messaging() -> Result<()> {
    const STDIN_FILENO: i32 = 0;
    const STDOUT_FILENO: i32 = 1;
    const O_BINARY: i32 = 0x8000;

    unsafe {
        if _setmode(STDIN_FILENO, O_BINARY) == -1 {
            anyhow::bail!("failed to switch stdin to binary mode");
        }

        if _setmode(STDOUT_FILENO, O_BINARY) == -1 {
            anyhow::bail!("failed to switch stdout to binary mode");
        }
    }

    Ok(())
}

#[cfg(windows)]
unsafe extern "C" {
    fn _setmode(fd: i32, mode: i32) -> i32;
}

#[cfg(test)]
mod tests {
    use anyhow::Context;
    use vaultkern_runtime_protocol::{
        AutofillCacheStateDto, AutofillCommittedFingerprintDto, AutofillPersistDispositionDto,
        AutofillPersistDurabilityDto, AutofillPersistOutcomeDto, AutofillPersistResultDto,
        RuntimeCommand, RuntimeResponse,
    };

    use super::{
        MAX_NATIVE_RESPONSE_BYTES, NativeMessage, claim_autofill_source_commit_crash_marker,
        command_response_from_result, configure_stdio_for_native_messaging, encode_native_response,
        format_error_chain, handle_command_response, is_committed_autofill_source_response,
        native_message_length_prefix, read_native_message_or_eof_with_limit,
        request_id_from_native_payload, run_loop_with_io, run_loop_with_io_with_limit,
        write_chunked_native_message, write_native_message,
    };
    use crate::{Runtime, RuntimeProtocolSession};

    fn durable_autofill_response(
        disposition: AutofillPersistDispositionDto,
        durability: AutofillPersistDurabilityDto,
    ) -> RuntimeResponse {
        RuntimeResponse::AutofillPersistResult(AutofillPersistResultDto {
            transaction_id: "transaction-crash-proof".into(),
            operation_id: "operation-crash-proof".into(),
            vault_id: "vault-crash-proof".into(),
            outcome: AutofillPersistOutcomeDto::Durable {
                disposition,
                entry_id: "entry-crash-proof".into(),
                durability,
                cache_state: AutofillCacheStateDto::Current,
                committed_fingerprint: AutofillCommittedFingerprintDto {
                    content_sha256: "00".repeat(32),
                    size_bytes: 42,
                },
                merge_summary: None,
                receipt_version: 1,
            },
        })
    }

    #[test]
    fn crash_hook_matches_only_new_source_commits() {
        assert!(is_committed_autofill_source_response(
            &durable_autofill_response(
                AutofillPersistDispositionDto::Committed,
                AutofillPersistDurabilityDto::Source,
            )
        ));
        assert!(!is_committed_autofill_source_response(
            &durable_autofill_response(
                AutofillPersistDispositionDto::Replayed,
                AutofillPersistDurabilityDto::Source,
            )
        ));
        assert!(!is_committed_autofill_source_response(
            &durable_autofill_response(
                AutofillPersistDispositionDto::Committed,
                AutofillPersistDurabilityDto::PendingRemoteCache,
            )
        ));
        assert!(!is_committed_autofill_source_response(
            &RuntimeResponse::Error(vaultkern_runtime_protocol::ErrorDto {
                code: "persist_failed".into(),
                message: "not durable".into(),
            })
        ));
    }

    #[test]
    fn crash_marker_is_claimed_and_synced_at_most_once() {
        let directory = std::env::temp_dir().join(format!(
            "vaultkern-command-loop-crash-marker-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&directory).expect("create marker directory");
        let marker = directory.join("committed.marker");
        let response = durable_autofill_response(
            AutofillPersistDispositionDto::Committed,
            AutofillPersistDurabilityDto::Source,
        );

        assert!(
            claim_autofill_source_commit_crash_marker(&response, &marker)
                .expect("claim first marker")
        );
        assert_eq!(
            std::fs::read_to_string(&marker).expect("read crash marker"),
            "transaction-crash-proof:operation-crash-proof\n"
        );
        assert!(
            !claim_autofill_source_commit_crash_marker(&response, &marker)
                .expect("existing marker must be a no-op")
        );

        std::fs::remove_dir_all(directory).expect("remove marker directory");
    }

    #[test]
    fn configures_stdio_before_native_message_loop() {
        configure_stdio_for_native_messaging().expect("configure stdio for native messaging");
    }

    #[test]
    fn native_response_frames_are_zeroizing_and_inject_request_ids_without_a_value_copy() {
        fn assert_zeroizing(_: &zeroize::Zeroizing<Vec<u8>>) {}

        let response = RuntimeResponse::Error(vaultkern_runtime_protocol::ErrorDto {
            code: "example".into(),
            message: "response-secret".into(),
        });
        let payload = encode_native_response(&response, Some("request-1")).unwrap();

        assert_zeroizing(&payload);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&payload).unwrap(),
            serde_json::json!({
                "type": "error",
                "code": "example",
                "message": "response-secret",
                "requestId": "request-1"
            })
        );
    }

    #[test]
    fn native_response_length_prefix_rejects_integer_truncation() {
        assert_eq!(
            native_message_length_prefix(u32::MAX as usize).unwrap(),
            u32::MAX.to_le_bytes()
        );
        if usize::BITS > u32::BITS {
            assert!(native_message_length_prefix(u32::MAX as usize + 1).is_err());
        }
    }

    #[test]
    fn native_message_loop_treats_clean_eof_as_shutdown() {
        let mut input = std::io::Cursor::new(Vec::<u8>::new());
        let mut output = Vec::new();

        run_loop_with_io(Runtime::for_tests(), &mut input, &mut output)
            .expect("clean EOF should shut down without an error");

        assert!(output.is_empty());
    }

    #[test]
    fn native_responses_over_chromes_one_mebibyte_limit_become_correlated_errors() {
        let response = RuntimeResponse::EntryAttachmentContent(
            vaultkern_runtime_protocol::EntryAttachmentContentDto {
                name: "oversized.bin".into(),
                data_base64: "A".repeat(1024 * 1024).into(),
                protect_in_memory: false,
            },
        );
        let mut output = Vec::new();

        write_native_message(&mut output, &response, Some("native-large-1"))
            .expect("oversized response should have a recoverable native response");
        assert!(output.len() <= 4 + MAX_NATIVE_RESPONSE_BYTES);

        let mut output = std::io::Cursor::new(output);
        let value =
            read_native_message_or_eof_with_limit::<serde_json::Value>(&mut output, 1024 * 1024)
                .expect("read native response");
        let NativeMessage::Message(value) = value else {
            panic!("expected a native response");
        };
        assert_eq!(value["type"], "error");
        assert_eq!(value["code"], "response_too_large");
        assert_eq!(value["requestId"], "native-large-1");
    }

    #[test]
    fn resident_native_responses_are_split_into_bounded_reassemblable_chunks() {
        let response = RuntimeResponse::EntryAttachmentContent(
            vaultkern_runtime_protocol::EntryAttachmentContentDto {
                name: "oversized.bin".into(),
                data_base64: "A".repeat(2 * 1024 * 1024).into(),
                protect_in_memory: false,
            },
        );
        let mut encoded = Vec::new();
        write_chunked_native_message(&mut encoded, &response, "native-chunked-1")
            .expect("write chunked native response");

        let mut input = std::io::Cursor::new(encoded);
        let mut parts = Vec::new();
        loop {
            match read_native_message_or_eof_with_limit::<serde_json::Value>(
                &mut input,
                MAX_NATIVE_RESPONSE_BYTES,
            )
            .expect("read native response chunk")
            {
                NativeMessage::Message(chunk) => {
                    assert_eq!(chunk["type"], "native_response_chunk");
                    assert_eq!(chunk["requestId"], "native-chunked-1");
                    parts.push(chunk["data"].as_str().expect("chunk data").to_owned());
                }
                NativeMessage::Eof => break,
                other => panic!("unexpected native chunk frame: {other:?}"),
            }
        }
        assert!(parts.len() > 1);
        let assembled: serde_json::Value =
            serde_json::from_str(&parts.concat()).expect("reassemble native response");
        assert_eq!(assembled["type"], "entry_attachment_content");
        assert_eq!(assembled["requestId"], "native-chunked-1");
        assert_eq!(
            assembled["dataBase64"].as_str().map(str::len),
            Some(2 * 1024 * 1024)
        );
    }

    #[test]
    fn native_message_reader_rejects_oversized_messages_without_draining_attacker_payload() {
        let mut input = Vec::new();
        input.extend_from_slice(&9_u32.to_le_bytes());
        input.extend_from_slice(b"oversized");
        input.extend_from_slice(&2_u32.to_le_bytes());
        input.extend_from_slice(b"{}");
        let mut input = std::io::Cursor::new(input);

        let result = read_native_message_or_eof_with_limit::<serde_json::Value>(&mut input, 8)
            .expect("read oversized native message");

        assert_eq!(
            result,
            NativeMessage::Oversized {
                length: 9,
                max_length: 8,
            }
        );
        assert_eq!(input.position(), 4);
    }

    #[test]
    fn native_message_loop_serializes_oversized_errors_and_exits_the_host() {
        let max_length = 1024;
        let mut input = Vec::new();
        input.extend_from_slice(&((max_length + 1) as u32).to_le_bytes());
        input.extend(vec![b'x'; max_length + 1]);
        let command = vaultkern_runtime_protocol::ProtocolEnvelope::new(
            RuntimeCommand::AddLocalVaultReference {
                path: Some("/definitely/missing/demo.kdbx".into()),
            },
        );
        let command_payload = serde_json::to_vec(&command).unwrap();
        input.extend_from_slice(&(command_payload.len() as u32).to_le_bytes());
        input.extend_from_slice(&command_payload);
        let mut input = std::io::Cursor::new(input);
        let mut output = Vec::new();

        run_loop_with_io_with_limit(
            Runtime::for_tests(),
            RuntimeProtocolSession::legacy_native_host(),
            &mut input,
            &mut output,
            max_length,
        )
        .expect("native loop should continue after oversized command");

        let mut output = std::io::Cursor::new(output);
        let first = read_response_from(&mut output);
        assert!(matches!(first, RuntimeResponse::Error(_)));
        let RuntimeResponse::Error(first_error) = first else {
            panic!("expected oversized error");
        };
        assert!(
            first_error
                .message
                .contains("native message exceeds maximum length")
        );
        assert_eq!(output.position(), output.get_ref().len() as u64);
    }

    #[test]
    fn native_message_loop_serializes_decode_errors_without_exiting_the_host() {
        let invalid_command = serde_json::json!({
            "version": 1,
            "requestId": "future-command",
            "command": { "type": "future_runtime_command" }
        });
        let invalid_payload = serde_json::to_vec(&invalid_command).unwrap();
        let valid_command =
            vaultkern_runtime_protocol::ProtocolEnvelope::new(RuntimeCommand::GetSessionState);
        let valid_payload = serde_json::to_vec(&valid_command).unwrap();
        let mut input = Vec::new();
        input.extend_from_slice(&(invalid_payload.len() as u32).to_le_bytes());
        input.extend_from_slice(&invalid_payload);
        input.extend_from_slice(&(valid_payload.len() as u32).to_le_bytes());
        input.extend_from_slice(&valid_payload);
        let mut input = std::io::Cursor::new(input);
        let mut output = Vec::new();

        run_loop_with_io(Runtime::for_tests(), &mut input, &mut output)
            .expect("native loop should continue after invalid command");

        let mut output = std::io::Cursor::new(output);
        let first = read_response_value_from(&mut output);
        let second = read_response_value_from(&mut output);
        assert_eq!(first["type"], "error");
        assert_eq!(first["code"], "invalid_request");
        assert!(
            first["message"]
                .as_str()
                .unwrap_or_default()
                .contains("failed to decode native message")
        );
        assert_eq!(second["type"], "session_state");
    }

    #[test]
    fn malformed_native_messages_extract_only_a_bounded_request_id() {
        let secret = "malformed-command-secret-must-not-be-retained";
        let invalid_command = serde_json::json!({
            "version": 1,
            "requestId": "request-1",
            "command": {
                "type": "future_runtime_command",
                "password": secret
            }
        });
        let payload = serde_json::to_vec(&invalid_command).unwrap();

        assert_eq!(
            request_id_from_native_payload(&payload).as_deref(),
            Some("request-1")
        );

        let oversized_request_id = "r".repeat(super::MAX_NATIVE_REQUEST_ID_BYTES + 1);
        let invalid_command = serde_json::json!({
            "version": 1,
            "requestId": oversized_request_id,
            "command": {
                "type": "future_runtime_command",
                "password": secret
            }
        });
        let payload = serde_json::to_vec(&invalid_command).unwrap();
        assert_eq!(request_id_from_native_payload(&payload), None);
    }

    #[test]
    fn native_message_loop_echoes_request_id_in_response() {
        let command = serde_json::json!({
            "version": 1,
            "requestId": "request-1",
            "command": { "type": "get_session_state" }
        });
        let command_payload = serde_json::to_vec(&command).unwrap();
        let mut input = Vec::new();
        input.extend_from_slice(&(command_payload.len() as u32).to_le_bytes());
        input.extend_from_slice(&command_payload);
        let mut input = std::io::Cursor::new(input);
        let mut output = Vec::new();

        run_loop_with_io(Runtime::for_tests(), &mut input, &mut output)
            .expect("native loop should handle request id envelope");

        let mut output = std::io::Cursor::new(output);
        let response = read_response_value_from(&mut output);
        assert_eq!(response["requestId"], "request-1");
        assert_eq!(response["type"], "session_state");
    }

    #[test]
    fn native_message_loop_rejects_an_unsupported_envelope_version() {
        let command = serde_json::json!({
            "version": 2,
            "requestId": "future-version",
            "command": { "type": "get_session_state" }
        });
        let payload = serde_json::to_vec(&command).unwrap();
        let mut input = Vec::new();
        input.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        input.extend_from_slice(&payload);
        let mut input = std::io::Cursor::new(input);
        let mut output = Vec::new();

        run_loop_with_io(Runtime::for_tests(), &mut input, &mut output).unwrap();

        let response = read_response_value_from(&mut std::io::Cursor::new(output));
        assert_eq!(response["requestId"], "future-version");
        assert_eq!(response["type"], "error");
        assert_eq!(response["code"], "unsupported_version");
    }

    fn read_response_from(reader: &mut impl std::io::Read) -> RuntimeResponse {
        let mut length = [0_u8; 4];
        reader
            .read_exact(&mut length)
            .expect("read native response length");
        let mut payload = vec![0_u8; u32::from_le_bytes(length) as usize];
        reader
            .read_exact(&mut payload)
            .expect("read native response payload");
        serde_json::from_slice(&payload).expect("decode native response")
    }

    fn read_response_value_from(reader: &mut impl std::io::Read) -> serde_json::Value {
        let mut length = [0_u8; 4];
        reader
            .read_exact(&mut length)
            .expect("read native response length");
        let mut payload = vec![0_u8; u32::from_le_bytes(length) as usize];
        reader
            .read_exact(&mut payload)
            .expect("read native response payload");
        serde_json::from_slice(&payload).expect("decode native response")
    }

    #[test]
    fn command_errors_are_serialized_without_exiting_the_host() {
        let mut runtime = Runtime::for_tests();

        let outcome = handle_command_response(
            &mut runtime,
            RuntimeCommand::AddLocalVaultReference {
                path: Some("/definitely/missing/demo.kdbx".into()),
            },
        );

        assert!(!outcome.fatal);
        let RuntimeResponse::Error(error) = outcome.response else {
            panic!("expected error response");
        };
        assert_eq!(error.code, "invalid_request");
        let stable_context = "failed to resolve vault path: /definitely/missing/demo.kdbx";
        let source_detail = error
            .message
            .strip_prefix(stable_context)
            .and_then(|message| message.strip_prefix(": "))
            .expect("serialized command error lost its stable context chain");
        assert!(!source_detail.is_empty());
    }

    #[test]
    fn command_response_converts_panics_to_fatal_protocol_errors() {
        let outcome = command_response_from_result(|| -> anyhow::Result<RuntimeResponse> {
            panic!("panic payload contains secret material");
        });

        assert_eq!(
            outcome.response,
            RuntimeResponse::Error(vaultkern_runtime_protocol::ErrorDto {
                code: "panic".into(),
                message: "runtime command panicked".into(),
            })
        );
        assert!(outcome.fatal);
    }

    #[test]
    fn error_messages_include_context_chain() {
        let error = Err::<(), _>(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "localized missing-file detail",
        ))
        .context("outer context")
        .unwrap_err();

        let message = format_error_chain(&error);

        assert_eq!(message, "outer context: localized missing-file detail");
    }
}
