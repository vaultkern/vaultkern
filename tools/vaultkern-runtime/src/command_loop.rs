use std::io::{Read, Write};
use std::panic::{AssertUnwindSafe, catch_unwind};

use anyhow::{Context, Result};
use vaultkern_runtime_protocol::{ErrorDto, ProtocolEnvelope, RuntimeCommand, RuntimeResponse};

use crate::Runtime;

const MAX_NATIVE_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

pub fn run_stdio_loop(runtime: Runtime) -> Result<()> {
    configure_stdio_for_native_messaging()?;

    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut stdin = stdin.lock();
    let mut stdout = stdout.lock();

    run_loop_with_io(runtime, &mut stdin, &mut stdout)
}

fn run_loop_with_io(
    mut runtime: Runtime,
    stdin: &mut impl Read,
    stdout: &mut impl Write,
) -> Result<()> {
    loop {
        let Some(envelope) = read_native_message_or_eof::<ProtocolEnvelope>(stdin)? else {
            return Ok(());
        };
        let response = handle_command_response(&mut runtime, envelope.command);
        write_native_message(stdout, &response)?;
    }
}

fn handle_command_response(runtime: &mut Runtime, command: RuntimeCommand) -> RuntimeResponse {
    command_response_from_result(|| runtime.handle(command))
}

fn command_response_from_result(run: impl FnOnce() -> Result<RuntimeResponse>) -> RuntimeResponse {
    match catch_unwind(AssertUnwindSafe(run)) {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => RuntimeResponse::Error(ErrorDto {
            code: "invalid_request".into(),
            message: format_error_chain(&error),
        }),
        Err(payload) => RuntimeResponse::Error(ErrorDto {
            code: "panic".into(),
            message: format!(
                "runtime command panicked: {}",
                panic_payload_message(payload.as_ref())
            ),
        }),
    }
}

fn panic_payload_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(message) = payload.downcast_ref::<&str>() {
        return (*message).to_owned();
    }
    if let Some(message) = payload.downcast_ref::<String>() {
        return message.clone();
    }
    "unknown panic".into()
}

pub(crate) fn format_error_chain(error: &anyhow::Error) -> String {
    error
        .chain()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(": ")
}

fn read_native_message_or_eof<T: serde::de::DeserializeOwned>(
    reader: &mut impl Read,
) -> Result<Option<T>> {
    let mut length = [0_u8; 4];
    let mut read = 0;
    while read < length.len() {
        let count = reader
            .read(&mut length[read..])
            .context("failed to read message length")?;
        if count == 0 {
            if read == 0 {
                return Ok(None);
            }
            anyhow::bail!("failed to read message length");
        }
        read += count;
    }

    let length = u32::from_le_bytes(length) as usize;
    if length > MAX_NATIVE_MESSAGE_BYTES {
        anyhow::bail!(
            "native message exceeds maximum length: {length} > {MAX_NATIVE_MESSAGE_BYTES}"
        );
    }
    let mut payload = vec![0_u8; length];
    reader
        .read_exact(&mut payload)
        .context("failed to read message payload")?;
    serde_json::from_slice(&payload)
        .context("failed to decode native message")
        .map(Some)
}

fn write_native_message(writer: &mut impl Write, response: &RuntimeResponse) -> Result<()> {
    let payload = serde_json::to_vec(response).context("failed to encode native message")?;
    let length = (payload.len() as u32).to_le_bytes();
    writer
        .write_all(&length)
        .context("failed to write message length")?;
    writer
        .write_all(&payload)
        .context("failed to write message payload")?;
    writer.flush().context("failed to flush native message")
}

#[cfg(not(windows))]
fn configure_stdio_for_native_messaging() -> Result<()> {
    Ok(())
}

#[cfg(windows)]
fn configure_stdio_for_native_messaging() -> Result<()> {
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
    use vaultkern_runtime_protocol::{RuntimeCommand, RuntimeResponse};

    use super::{
        command_response_from_result, configure_stdio_for_native_messaging, format_error_chain,
        handle_command_response, read_native_message_or_eof, run_loop_with_io,
    };
    use crate::Runtime;

    #[test]
    fn configures_stdio_before_native_message_loop() {
        configure_stdio_for_native_messaging().expect("configure stdio for native messaging");
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
    fn native_message_reader_rejects_oversized_messages_before_allocating() {
        let mut input = std::io::Cursor::new(u32::MAX.to_le_bytes().to_vec());

        let error = read_native_message_or_eof::<serde_json::Value>(&mut input).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("native message exceeds maximum length")
        );
    }

    #[test]
    fn command_errors_are_serialized_without_exiting_the_host() {
        let mut runtime = Runtime::for_tests();

        let response = handle_command_response(
            &mut runtime,
            RuntimeCommand::AddLocalVaultReference {
                path: Some("/definitely/missing/demo.kdbx".into()),
            },
        );

        let RuntimeResponse::Error(error) = response else {
            panic!("expected error response");
        };
        assert_eq!(error.code, "invalid_request");
        assert!(
            error
                .message
                .contains("failed to resolve vault path: /definitely/missing/demo.kdbx")
        );
        assert!(
            error.message.contains("No such file")
                || error.message.contains("cannot find the path")
        );
    }

    #[test]
    fn command_response_converts_panics_to_protocol_errors() {
        let response = command_response_from_result(|| -> anyhow::Result<RuntimeResponse> {
            panic!("passkey assertion panic");
        });

        assert_eq!(
            response,
            RuntimeResponse::Error(vaultkern_runtime_protocol::ErrorDto {
                code: "panic".into(),
                message: "runtime command panicked: passkey assertion panic".into(),
            })
        );
    }

    #[test]
    fn error_messages_include_context_chain() {
        let error = std::fs::read("/definitely/missing/demo.kdbx")
            .context("outer context")
            .unwrap_err();

        let message = format_error_chain(&error);

        assert!(message.contains("outer context"));
        assert!(message.contains("No such file") || message.contains("cannot find the path"));
    }
}
