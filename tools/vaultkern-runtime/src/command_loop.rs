use std::io::{Read, Write};

use anyhow::{Context, Result};
use vaultkern_runtime_protocol::{ErrorDto, ProtocolEnvelope, RuntimeCommand, RuntimeResponse};

use crate::Runtime;

pub fn run_stdio_loop(mut runtime: Runtime) -> Result<()> {
    configure_stdio_for_native_messaging()?;

    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut stdin = stdin.lock();
    let mut stdout = stdout.lock();

    loop {
        let envelope = read_native_message::<ProtocolEnvelope>(&mut stdin)?;
        let response = handle_command_response(&mut runtime, envelope.command);
        write_native_message(&mut stdout, &response)?;
    }
}

fn handle_command_response(runtime: &mut Runtime, command: RuntimeCommand) -> RuntimeResponse {
    match runtime.handle(command) {
        Ok(response) => response,
        Err(error) => RuntimeResponse::Error(ErrorDto {
            code: "invalid_request".into(),
            message: format_error_chain(&error),
        }),
    }
}

pub(crate) fn format_error_chain(error: &anyhow::Error) -> String {
    error
        .chain()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(": ")
}

fn read_native_message<T: serde::de::DeserializeOwned>(reader: &mut impl Read) -> Result<T> {
    let mut length = [0_u8; 4];
    reader
        .read_exact(&mut length)
        .context("failed to read message length")?;
    let length = u32::from_le_bytes(length) as usize;
    let mut payload = vec![0_u8; length];
    reader
        .read_exact(&mut payload)
        .context("failed to read message payload")?;
    serde_json::from_slice(&payload).context("failed to decode native message")
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
        configure_stdio_for_native_messaging, format_error_chain, handle_command_response,
    };
    use crate::Runtime;

    #[test]
    fn configures_stdio_before_native_message_loop() {
        configure_stdio_for_native_messaging().expect("configure stdio for native messaging");
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
    fn error_messages_include_context_chain() {
        let error = std::fs::read("/definitely/missing/demo.kdbx")
            .context("outer context")
            .unwrap_err();

        let message = format_error_chain(&error);

        assert!(message.contains("outer context"));
        assert!(message.contains("No such file") || message.contains("cannot find the path"));
    }
}
