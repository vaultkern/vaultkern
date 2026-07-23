use vaultkern_runtime::{Runtime, RuntimeProtocolDispatch, RuntimeProtocolSession};
use vaultkern_runtime_protocol::{ErrorDto, RuntimeCommand, RuntimeResponse};

const DRIVE_ID: &str = "memory-drive";
const ITEM_ID: &str = "memory-item";

pub struct ProviderSnapshot {
    pub bytes: Vec<u8>,
    pub revision: u64,
}

pub struct RuntimeProtocolHarness {
    runtime: Runtime,
    protocol_session: RuntimeProtocolSession,
}

impl RuntimeProtocolHarness {
    pub fn resident_with_in_memory_vault(bytes: Vec<u8>) -> Self {
        Self::with_protocol_session(bytes, RuntimeProtocolSession::resident_app())
    }

    pub fn browser_with_in_memory_vault(bytes: Vec<u8>) -> Self {
        Self::with_protocol_session(bytes, RuntimeProtocolSession::browser_extension())
    }

    fn with_protocol_session(bytes: Vec<u8>, protocol_session: RuntimeProtocolSession) -> Self {
        Self {
            runtime: Runtime::for_tests_with_onedrive_item(
                DRIVE_ID,
                ITEM_ID,
                "Architecture Acceptance.kdbx",
                "acceptance@example.com",
                bytes,
            ),
            protocol_session,
        }
    }

    pub fn drive_id(&self) -> &'static str {
        DRIVE_ID
    }

    pub fn item_id(&self) -> &'static str {
        ITEM_ID
    }

    pub fn command(&mut self, command: RuntimeCommand) -> RuntimeResponse {
        match self.protocol_session.accept(command) {
            RuntimeProtocolDispatch::Respond(response) => response,
            RuntimeProtocolDispatch::Dispatch(command) => {
                self.runtime.handle(command).unwrap_or_else(|error| {
                    RuntimeResponse::Error(ErrorDto {
                        code: "runtime_error".into(),
                        message: format!("{error:#}"),
                    })
                })
            }
        }
    }

    pub fn provider_snapshot(&self) -> ProviderSnapshot {
        ProviderSnapshot {
            bytes: self
                .runtime
                .read_test_onedrive_item_bytes(DRIVE_ID, ITEM_ID)
                .expect("read in-memory Provider snapshot"),
            revision: self
                .runtime
                .test_onedrive_item_revision(DRIVE_ID, ITEM_ID)
                .expect("read in-memory Provider revision"),
        }
    }

    pub fn reject_next_publication_as_stale(&mut self, remote_head: Vec<u8>) {
        self.runtime
            .queue_test_onedrive_precondition_failure(Some(remote_head));
    }
}
