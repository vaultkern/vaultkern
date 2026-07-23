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
    remote_cache_dir: Option<tempfile::TempDir>,
}

impl RuntimeProtocolHarness {
    pub fn resident() -> Self {
        Self {
            runtime: Runtime::for_tests(),
            protocol_session: RuntimeProtocolSession::resident_app(),
            remote_cache_dir: None,
        }
    }

    pub fn resident_with_in_memory_vault(bytes: Vec<u8>) -> Self {
        Self::with_protocol_session(bytes, RuntimeProtocolSession::resident_app())
    }

    pub fn browser_with_in_memory_vault(bytes: Vec<u8>) -> Self {
        Self::with_protocol_session(bytes, RuntimeProtocolSession::browser_extension())
    }

    fn with_protocol_session(bytes: Vec<u8>, protocol_session: RuntimeProtocolSession) -> Self {
        let remote_cache_dir = tempfile::tempdir().expect("create architecture cache directory");
        Self {
            runtime: Runtime::for_tests_at_with_onedrive_item_and_remote_cache(
                1_700_000_000,
                DRIVE_ID,
                ITEM_ID,
                "Architecture Acceptance.kdbx",
                "acceptance@example.com",
                bytes,
                remote_cache_dir.path(),
            ),
            protocol_session,
            remote_cache_dir: Some(remote_cache_dir),
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

    pub fn provider_write_count(&self) -> usize {
        self.runtime.test_onedrive_access_counts().writes
    }

    pub fn restart_resident(&mut self) {
        let snapshot = self.provider_snapshot();
        let remote_cache_dir = self
            .remote_cache_dir
            .as_ref()
            .expect("restart requires an in-memory Provider harness");
        let mut runtime = Runtime::for_tests_at_with_onedrive_item_and_remote_cache(
            1_700_000_001,
            DRIVE_ID,
            ITEM_ID,
            "Architecture Acceptance.kdbx",
            "acceptance@example.com",
            snapshot.bytes,
            remote_cache_dir.path(),
        );
        runtime
            .set_test_onedrive_item_revision(DRIVE_ID, ITEM_ID, snapshot.revision)
            .expect("restore in-memory Provider revision");
        self.runtime = runtime;
        self.protocol_session = RuntimeProtocolSession::resident_app();
    }

    pub fn reject_next_publication_as_stale(&mut self, remote_head: Vec<u8>) {
        self.runtime
            .queue_test_onedrive_precondition_failure(Some(remote_head));
    }

    pub fn fail_next_conflict_copy_preservation(&self) {
        self.runtime.fail_next_test_onedrive_conflict_copy();
    }

    pub fn provider_item_bytes(&self, item_id: &str) -> Vec<u8> {
        self.runtime
            .read_test_onedrive_item_bytes(DRIVE_ID, item_id)
            .expect("read in-memory Provider item")
    }

    pub fn make_next_publication_outcome_unknown_and_readback_unavailable(&mut self) {
        self.runtime
            .queue_test_onedrive_ambiguous_write_with_unavailable_readback(false);
    }
}
